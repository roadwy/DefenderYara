
rule Trojan_Win32_Ursnif_VDS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 54 01 02 88 95 fb f7 ff ff 8a 54 01 03 8a ca 88 95 fa f7 ff ff 80 e1 f0 c0 e1 02 0a 0c 03 88 8d f9 f7 ff ff 8b 0d ?? ?? ?? ?? 81 f9 e9 05 00 00 0f 84 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}