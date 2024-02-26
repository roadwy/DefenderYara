
rule Trojan_Win32_FormBook_AMF_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe c0 32 c1 c0 c0 02 2a c1 c0 c0 03 04 56 f6 d0 2c 19 34 18 f6 d8 d0 c8 04 0a f6 d0 02 c1 d0 c0 2a c1 34 92 } //00 00 
	condition:
		any of ($a_*)
 
}