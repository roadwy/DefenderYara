
rule Trojan_Win32_PonyStealer_PD_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {85 c0 46 66 85 db ff 37 85 ff [0-6f] 59 [0-10] 31 f1 [0-10] 39 c1 75 } //1
		$a_02_1 = {85 ff 46 81 fb ?? ?? ?? ?? ff 37 66 ?? ?? ?? ?? 59 [0-10] 31 f1 [0-10] 39 c1 0f 85 ?? ?? ff ff } //1
		$a_02_2 = {66 85 db 46 81 fb ?? ?? ?? ?? ff 37 [0-bf] 59 [0-10] 31 f1 [0-10] 39 c1 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}