
rule Trojan_Win32_Neoreblamy_NSL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 22 83 65 b8 00 eb 07 8b 45 b8 40 89 45 b8 } //1
		$a_03_1 = {6b c0 00 8d 84 05 ?? ?? ff ff 6a 04 59 c1 e1 02 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}