
rule Trojan_Win32_Lazy_AMOA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AMOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ce ff 46 8d 3c 32 8d 2c 30 8a 1f 30 5d 00 39 ce 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}