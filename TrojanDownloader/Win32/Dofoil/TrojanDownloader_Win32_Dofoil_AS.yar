
rule TrojanDownloader_Win32_Dofoil_AS{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AS,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 08 cf 45 00 89 45 f8 81 45 f8 43 0d 00 00 8b 45 f8 a3 08 cf 45 00 ff 15 08 cf 45 00 } //1
		$a_01_1 = {a1 0c cf 45 00 8a 8c 10 76 f1 08 00 a1 08 cf 45 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}