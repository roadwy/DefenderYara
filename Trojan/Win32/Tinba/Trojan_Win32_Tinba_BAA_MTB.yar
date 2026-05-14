
rule Trojan_Win32_Tinba_BAA_MTB{
	meta:
		description = "Trojan:Win32/Tinba.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 d1 88 55 b0 8b 45 08 03 45 cc 8a 4d 90 88 48 ff 0f be 55 d0 0f af 55 bc 8b 45 b8 2b c2 89 45 b8 0f be 4d b4 8b 55 bc 03 d1 89 55 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}