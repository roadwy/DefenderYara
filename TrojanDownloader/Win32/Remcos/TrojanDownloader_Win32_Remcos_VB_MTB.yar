
rule TrojanDownloader_Win32_Remcos_VB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Remcos.VB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a3 0f c4 fe 63 e8 d3 6a e7 d0 70 e6 cd 6a e7 d0 6a e7 d0 4d d1 ed 4c cd ee 4a ce ef 4e d0 ee 52 cf ec 46 d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}