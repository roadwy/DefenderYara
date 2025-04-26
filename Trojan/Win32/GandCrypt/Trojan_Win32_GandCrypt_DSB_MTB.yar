
rule Trojan_Win32_GandCrypt_DSB_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.DSB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 41 03 8a d0 8a d8 24 f0 80 e2 fc c0 e0 02 0a 01 c0 e2 04 0a 51 01 c0 e3 06 0a 59 02 88 04 3e 46 88 14 3e 46 88 1c 3e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}