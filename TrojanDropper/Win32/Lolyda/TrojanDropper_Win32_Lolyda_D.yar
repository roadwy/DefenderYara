
rule TrojanDropper_Win32_Lolyda_D{
	meta:
		description = "TrojanDropper:Win32/Lolyda.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 4f 4e 74 53 5c 43 6f 6d 52 65 73 2e 64 6c 6c } //1 FONtS\ComRes.dll
		$a_00_1 = {46 6f 6e 74 53 5c 67 74 68 25 30 32 78 2a 2e 74 74 66 } //1 FontS\gth%02x*.ttf
		$a_02_2 = {2d 20 05 00 00 8d 8d ?? ?? ?? ?? 50 68 20 05 00 00 8d 95 ?? ?? ?? ?? 51 52 e8 [0-0f] 90 90 [0-0f] 8d 85 ?? ?? ?? ?? 68 20 05 00 00 8d 8d ?? ?? ?? ?? 50 51 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}