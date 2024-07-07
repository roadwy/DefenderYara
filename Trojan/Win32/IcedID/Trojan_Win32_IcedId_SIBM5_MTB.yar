
rule Trojan_Win32_IcedId_SIBM5_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBM5!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 c1 c9 90 01 01 80 3a 61 90 02 10 72 90 01 01 48 03 c8 48 83 e9 90 01 01 eb 90 01 01 48 03 c8 0f b6 44 24 90 01 01 48 ff c2 66 44 03 c5 75 90 00 } //1
		$a_03_1 = {33 c0 0f b6 0a 90 02 10 c1 c8 90 01 01 48 8d 52 01 0f be c9 03 c1 0f b6 0a 84 c9 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}