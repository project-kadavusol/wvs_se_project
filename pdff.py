from fpdf import FPDF as fp
from PyPDF2 import PdfWriter,PdfReader
import os

def txt_to_pdf(filename): 
    templete="downloads/PDF_TEMPLETE.pdf"
    txt= f"downloads/{filename}"
    file_name=txt.replace(".txt",".pdf")
    pr=PdfReader(templete)
    pw=PdfWriter()
    for page in pr.pages:
        pw.add_page(page)

    pdf_file=fp()
    pdf_file.add_page()
    pdf_file.set_font('Courier', size=10)  
    with open(txt,'r') as ou:
        text=ou.read()
    pdf_file.multi_cell(0,5,text)
    temp_file='pdf\\temp.pdf'
    pdf_file.output(temp_file)
    t_read=PdfReader(temp_file)
    for page in t_read.pages:
        pw.add_page(page)
    
    with open(file_name,'wb') as nf:
        pw.write(file_name)
    
    os.remove(temp_file)

    return file_name