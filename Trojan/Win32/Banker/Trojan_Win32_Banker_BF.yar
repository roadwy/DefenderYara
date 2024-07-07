
rule Trojan_Win32_Banker_BF{
	meta:
		description = "Trojan:Win32/Banker.BF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 67 72 61 6d 61 5f 4f 6e 6c 69 6e 65 2e 62 61 74 } //1 Telegrama_Online.bat
		$a_03_1 = {0d 0a 73 65 74 20 2d 90 01 04 2d 3d 90 01 01 0d 0a 73 65 74 20 2d 90 01 04 2d 3d 90 01 01 0d 0a 25 2d 90 01 04 2d 25 25 2d 90 01 04 2d 25 25 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}