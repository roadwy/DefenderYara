
rule TrojanDownloader_O97M_Powdow_DPE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 3d 22 63 3a 7e 7e 75 73 65 72 73 7e 7e 22 26 65 6e 76 69 72 6f 6e 28 22 75 73 65 72 6e 61 6d 65 22 29 26 22 7e 7e 24 24 70 70 64 24 24 74 24 24 7e 7e 72 6f 24 24 6d 69 6e 67 7e 7e 6d 69 63 72 6f 73 6f 66 74 7e 7e 77 69 6e 64 6f 77 73 7e 7e 73 74 24 24 72 74 6d 65 6e 75 7e 7e 70 72 6f 67 72 24 24 6d 73 7e 7e 73 74 24 24 72 74 75 70 7e 7e 75 70 64 24 24 74 65 21 21 22 3a 3a } //01 00  subauto_open()="c:~~users~~"&environ("username")&"~~$$ppd$$t$$~~ro$$ming~~microsoft~~windows~~st$$rtmenu~~progr$$ms~~st$$rtup~~upd$$te!!"::
		$a_01_1 = {3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 21 21 22 2c 22 2e 6a 73 22 29 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 24 24 22 2c 22 61 22 29 3a 3a 3a 3a 3a 3d } //01 00  :=vba.replace(,"!!",".js"):::::=vba.replace(,"$$","a"):::::=
		$a_01_2 = {21 21 5b 5d 29 3b 22 64 65 62 75 67 2e 70 72 69 6e 74 3a 3a 3a 63 6c 6f 73 65 64 65 62 75 67 2e 70 72 69 6e 74 6f 70 65 6e 66 6f 72 6f 75 74 70 75 74 61 73 23 31 64 65 62 75 67 2e 70 72 69 6e 74 6f 70 65 6e 66 6f 72 6f 75 74 70 75 74 61 73 23 32 64 65 62 75 67 2e 70 72 69 6e 74 70 72 69 6e 74 23 31 2c 2b 31 2b 32 2b 33 64 65 62 75 67 2e 70 72 69 6e 74 70 72 69 6e 74 23 32 2c 2b 31 2b 32 2b 33 63 6c 6f 73 65 3d } //01 00  !![]);"debug.print:::closedebug.printopenforoutputas#1debug.printopenforoutputas#2debug.printprint#1,+1+2+3debug.printprint#2,+1+2+3close=
		$a_01_3 = {29 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 7e 7e 22 2c 22 6a 73 63 72 69 70 74 22 29 64 65 62 75 67 2e 70 72 69 6e 74 63 61 6c 6c 73 68 65 6c 6c 21 28 29 64 65 62 75 67 2e 70 72 69 6e 74 65 6e 64 73 75 62 } //00 00  ):::::=vba.replace(,"~~","jscript")debug.printcallshell!()debug.printendsub
	condition:
		any of ($a_*)
 
}