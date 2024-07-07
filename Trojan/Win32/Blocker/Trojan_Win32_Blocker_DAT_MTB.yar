
rule Trojan_Win32_Blocker_DAT_MTB{
	meta:
		description = "Trojan:Win32/Blocker.DAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 00 6c 70 ff fb 3d 2f 70 ff 1c 4e 04 f4 00 1c 24 04 fc c8 f4 00 1c 2b 04 fc c8 f4 00 1c 32 04 fc c8 f4 00 1c 39 04 fc c8 f5 02 00 00 00 6c 78 } //2
		$a_01_1 = {35 3c ff 1c 6a 05 f4 00 1c 16 05 fc c8 f4 00 1c 1d 05 fc c8 f4 00 1c 24 05 fc c8 f4 00 1c 2b 05 fc c8 f5 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}