
rule Trojan_Win32_Badur_EDE_MTB{
	meta:
		description = "Trojan:Win32/Badur.EDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0c 90 2b 8d 0c ff ff ff 8b 95 64 ff ff ff 8b 45 b4 89 0c 90 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}