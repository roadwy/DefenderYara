
rule Trojan_Win32_AveMariaRAT_F_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 04 0b c0 c8 90 01 01 32 87 90 01 04 41 88 44 90 01 01 ff 8d 47 90 01 01 99 bf 90 01 04 f7 ff 8b fa 3b ce 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}