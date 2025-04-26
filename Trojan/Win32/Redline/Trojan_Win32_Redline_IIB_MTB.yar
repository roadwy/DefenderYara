
rule Trojan_Win32_Redline_IIB_MTB{
	meta:
		description = "Trojan:Win32/Redline.IIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 4e 34 dc 59 88 86 ?? ?? ?? ?? e8 07 c0 f7 ff 50 e8 cf bf f7 ff 8a 86 ?? ?? ?? ?? 34 ac c7 04 24 ?? ?? ?? ?? 2c 65 34 22 2c 73 88 86 ?? ?? ?? ?? e8 a1 eb fc ff 30 86 ?? ?? ?? ?? 46 59 81 fe ac 04 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}