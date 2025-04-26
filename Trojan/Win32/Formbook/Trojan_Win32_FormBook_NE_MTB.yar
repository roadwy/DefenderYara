
rule Trojan_Win32_FormBook_NE_MTB{
	meta:
		description = "Trojan:Win32/FormBook.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 f1 cb 00 00 00 88 4d db 0f b6 75 db c1 fe 05 0f b6 7d db c1 e7 03 89 f3 09 fb 88 5d db 0f b6 75 db 89 c1 29 f1 88 4d db 0f b6 75 db 89 f1 83 f1 15 88 4d db 0f b6 75 db 89 f1 83 f1 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}