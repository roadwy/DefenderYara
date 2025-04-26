
rule Trojan_Win32_Johnnie_ER_MTB{
	meta:
		description = "Trojan:Win32/Johnnie.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 80 83 c0 01 89 45 80 8b 4d f4 83 e9 01 39 4d 80 ?? ?? 8b 55 f4 83 ea 01 2b 55 80 8b 45 f8 0f be 0c 10 f7 d1 8b 55 84 03 55 80 88 0a eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}