
rule Trojan_Win32_RedLineStealer_MBA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {40 00 8c 10 40 00 b0 10 40 00 00 cb } //1
		$a_01_1 = {40 75 73 65 72 31 32 33 33 31 31 61 5f 63 72 79 70 74 65 64 2e 65 78 65 } //1 @user123311a_crypted.exe
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_3 = {46 6f 72 74 6e 69 74 65 20 63 68 65 61 74 } //1 Fortnite cheat
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}