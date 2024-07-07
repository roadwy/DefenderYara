
rule Trojan_Win32_Gentrodet_B_bit{
	meta:
		description = "Trojan:Win32/Gentrodet.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 0c 30 02 c8 40 3b c2 72 f6 } //1
		$a_01_1 = {5c 2a 2e 2a 2e 6c 6e 6b } //1 \*.*.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}