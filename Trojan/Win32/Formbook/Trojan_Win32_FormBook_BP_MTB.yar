
rule Trojan_Win32_FormBook_BP_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 c2 0f b7 [0-25] 90 13 [0-10] 46 [0-25] ff 37 [0-25] 90 18 [0-10] 0f 6e da [0-25] 31 f2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}