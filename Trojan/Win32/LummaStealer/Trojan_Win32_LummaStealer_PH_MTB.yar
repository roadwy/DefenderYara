
rule Trojan_Win32_LummaStealer_PH_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 8b 14 98 8b 44 24 ?? 8b 48 08 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}