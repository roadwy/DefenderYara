
rule Trojan_Win32_CerberCrypt_C_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 02 8b 55 ?? 03 55 ?? 8b 45 ?? 8a 04 10 32 c1 88 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}