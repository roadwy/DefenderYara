
rule Trojan_Win32_Hesv_HNC_MTB{
	meta:
		description = "Trojan:Win32/Hesv.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 7b b1 42 6c 32 7c 34 41 85 44 f3 34 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}