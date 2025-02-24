
rule Trojan_Win32_Neoreblamy_BAD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 85 db 50 22 c7 85 ?? ?? ff ff 9d cd 00 b0 c7 85 ?? ?? ff ff fa f5 39 89 8b 85 ?? ?? ff ff f7 d8 83 f8 f7 77 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}