
rule Trojan_Win32_SystemBC_CCIM_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.CCIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 32 69 f6 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 99 bf ?? ?? ?? ?? f7 ff 03 f0 03 ce 81 f1 ?? ?? ?? ?? 88 8d } //2
		$a_03_1 = {33 d0 88 55 ?? 0f b6 45 ?? 6b c0 ?? 0f b6 4d ?? 0f b6 55 ?? 0b ca 33 c1 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}