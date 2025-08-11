
rule Trojan_Win32_Lazy_PGLZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.PGLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 8b 45 f4 01 d0 0f b6 00 89 c2 8b 45 d8 89 d1 31 c1 8b 55 f0 8b 45 f4 01 d0 89 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 ec 72 d4 } //5
		$a_01_1 = {8b 55 fc 48 8b 45 f0 48 01 d0 0f b6 00 89 c2 8b 45 cc 89 d1 31 c1 8b 55 fc 48 8b 45 f0 48 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 3b 45 ec 72 d0 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}