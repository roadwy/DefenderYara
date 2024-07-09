
rule Trojan_Win32_Mycop_NM_MTB{
	meta:
		description = "Trojan:Win32/Mycop.NM.MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 1b 84 c0 0f 94 c0 88 44 24 ?? eb 14 85 db 74 10 8d 45 ff 3b f8 73 05 66 89 0c 7b 47 8a 44 24 13 } //5
		$a_01_1 = {6a 77 77 66 61 69 68 71 64 75 2e 64 6f 63 78 } //1 jwwfaihqdu.docx
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}