
rule Trojan_Win32_FormBook_AFN_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c0 89 45 bc 8b 45 dc b9 ?? ?? ?? ?? 99 f7 f9 8b 45 bc 0f b6 34 10 8b 45 cc 8b 4d dc 0f b6 14 08 31 f2 88 14 08 8b 45 dc 83 c0 01 89 45 dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}