
rule Ransom_Win32_Crypmod_MK_MTB{
	meta:
		description = "Ransom:Win32/Crypmod.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 7a 69 70 } //01 00  .zip
		$a_01_1 = {25 64 20 2b 20 25 64 20 3d 20 25 64 } //01 00  %d + %d = %d
		$a_01_2 = {65 63 68 6f 20 4f 70 73 2c 20 73 65 75 73 20 61 72 71 75 69 76 6f 73 20 66 6f 72 61 6d 20 63 72 69 70 74 6f 67 72 61 66 61 64 6f 73 } //00 00  echo Ops, seus arquivos foram criptografados
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Crypmod_MK_MTB_2{
	meta:
		description = "Ransom:Win32/Crypmod.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //Go build ID:  01 00 
		$a_80_1 = {2e 61 76 69 2e 63 73 73 2e 64 6f 63 2e 67 69 66 2e 68 74 6d 2e 6a 70 67 2e 6d 6f 76 2e 6d 70 33 2e 6d 70 34 2e 6d 70 67 2e 70 64 66 2e 70 6e 67 2e 70 70 74 2e 72 61 72 2e 73 76 67 2e 74 78 74 2e 78 6c 73 2e 78 6d 6c 2e 7a 69 70 } //.avi.css.doc.gif.htm.jpg.mov.mp3.mp4.mpg.pdf.png.ppt.rar.svg.txt.xls.xml.zip  01 00 
		$a_03_2 = {84 02 0f b6 33 43 45 31 c6 96 0f b6 c0 96 8b 34 b2 c1 e8 90 01 01 31 f0 39 cd 7c e6 90 00 } //01 00 
		$a_80_3 = {68 69 6a 61 63 6b 65 64 } //hijacked  01 00 
		$a_80_4 = {52 45 41 44 4d 45 2e 74 78 74 } //README.txt  00 00 
	condition:
		any of ($a_*)
 
}