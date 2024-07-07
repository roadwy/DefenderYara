
rule Trojan_Win32_Strab_GPA_MTB{
	meta:
		description = "Trojan:Win32/Strab.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {c0 c8 03 32 83 90 01 04 88 81 00 40 90 01 02 8d 43 01 6a 0d 5b 99 f7 fb 41 8b da 3b ce 72 db 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}