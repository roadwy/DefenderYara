
rule Trojan_Win32_FormBook_MK_MSR{
	meta:
		description = "Trojan:Win32/FormBook.MK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 85 c0 33 0c 24 66 85 db 5e 85 d2 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}