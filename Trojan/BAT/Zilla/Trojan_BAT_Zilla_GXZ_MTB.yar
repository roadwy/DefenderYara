
rule Trojan_BAT_Zilla_GXZ_MTB{
	meta:
		description = "Trojan:BAT/Zilla.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0a 00 00 28 ?? ?? ?? 0a fe 0a 00 00 28 ?? ?? ?? 0a fe 0c 0b 00 6a 58 fe 0c 0e 00 20 04 00 00 00 5a 6a 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 0f 00 fe 0c 0f 00 fe 09 01 00 20 05 00 00 00 6f ?? ?? ?? 0a fe 0e 10 00 fe 0c 10 00 } //10
		$a_80_1 = {54 6e 52 51 63 6d 39 30 5a 57 4e 30 56 6d 6c 79 64 48 56 68 62 45 31 6c 62 57 39 79 65 51 3d 3d } //TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}