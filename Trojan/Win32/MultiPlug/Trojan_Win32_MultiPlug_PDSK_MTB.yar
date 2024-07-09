
rule Trojan_Win32_MultiPlug_PDSK_MTB{
	meta:
		description = "Trojan:Win32/MultiPlug.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ff 7f 00 00 } //2
		$a_02_1 = {6a 00 ff d5 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}