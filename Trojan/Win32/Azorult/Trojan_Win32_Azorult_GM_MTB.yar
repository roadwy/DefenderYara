
rule Trojan_Win32_Azorult_GM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ff 69 04 00 00 [0-10] 30 04 33 [0-10] 8d 44 24 ?? ?? 8d 4c 24 [0-06] 8d 54 24 [0-10] 46 3b f7 7c } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}