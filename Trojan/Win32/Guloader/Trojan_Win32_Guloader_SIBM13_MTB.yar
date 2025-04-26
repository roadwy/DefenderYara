
rule Trojan_Win32_Guloader_SIBM13_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBM13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e cb [0-0a] 50 [0-0a] 31 f6 [0-0a] ff 34 30 [0-0a] 5b [0-0a] 66 0f 6e eb [0-0a] 90 18 [0-0a] 66 0f ef e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}