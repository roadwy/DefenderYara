
rule TrojanDropper_Win32_Nebuler_C{
	meta:
		description = "TrojanDropper:Win32/Nebuler.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 bd 6c 6a fe ff 00 98 00 00 73 29 8b 85 6c 6a fe ff 0f b6 ?? ?? ?? ?? ?? ?? 8b 95 6c 6a fe ff 0f b6 82 00 60 40 00 33 c1 8b 8d 6c 6a fe ff 88 81 00 60 40 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}