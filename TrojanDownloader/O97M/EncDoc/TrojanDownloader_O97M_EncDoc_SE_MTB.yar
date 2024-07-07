
rule TrojanDownloader_O97M_EncDoc_SE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 72 28 31 2c 62 61 73 65 36 34 63 68 61 72 73 2c 6d 69 64 24 28 62 61 73 65 36 34 73 74 72 69 6e 67 2c 69 2b 32 2c 31 29 29 2d 31 62 79 74 65 73 28 69 2b 32 29 3d 69 6e 73 74 72 28 31 2c 62 61 73 65 36 34 63 68 61 72 73 2c 6d 69 64 24 28 62 61 73 65 36 34 73 74 72 69 6e 67 2c 69 2b 33 2c 31 29 29 } //1 instr(1,base64chars,mid$(base64string,i+2,1))-1bytes(i+2)=instr(1,base64chars,mid$(base64string,i+3,1))
		$a_01_1 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
		$a_01_2 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 76 61 72 32 31 3d 76 61 72 33 31 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 61 70 70 64 61 74 61 22 29 76 61 72 32 31 3d 76 61 72 32 31 2b 22 5c 68 69 68 69 2e 70 73 31 } //1 =createobject("wscript.shell")var21=var31.specialfolders("appdata")var21=var21+"\hihi.ps1
		$a_01_3 = {77 69 6e 68 74 74 70 72 65 71 2e 6f 70 65 6e 22 67 65 74 22 2c 6c 69 6e 6b 2c 66 61 6c 73 65 77 69 6e 68 74 74 70 72 65 71 2e 73 65 6e 64 66 69 6c 65 63 6f 6e 74 65 6e 74 } //1 winhttpreq.open"get",link,falsewinhttpreq.sendfilecontent
		$a_01_4 = {3d 31 6f 73 74 72 65 61 6d 2e 77 72 69 74 65 66 69 6c 65 63 6f 6e 74 65 6e 74 6f 73 74 72 65 61 6d 2e 73 61 76 65 74 6f 66 69 6c 65 76 61 72 32 31 } //1 =1ostream.writefilecontentostream.savetofilevar21
		$a_01_5 = {68 74 74 70 73 3a 2f 2f 67 69 73 74 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 68 6f 61 6e 67 61 32 64 74 6b 36 38 2f 33 66 65 32 30 61 31 61 32 31 64 66 39 39 32 66 61 34 36 32 31 34 32 62 31 37 66 33 63 65 65 30 2f 72 61 77 2f 61 66 30 35 32 61 31 33 39 37 30 61 64 31 35 35 37 66 30 65 31 32 32 35 65 38 32 66 34 61 61 36 36 31 39 63 30 34 37 66 2f 68 69 68 69 2e 70 73 31 } //1 https://gist.githubusercontent.com/hoanga2dtk68/3fe20a1a21df992fa462142b17f3cee0/raw/af052a13970ad1557f0e1225e82f4aa6619c047f/hihi.ps1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}