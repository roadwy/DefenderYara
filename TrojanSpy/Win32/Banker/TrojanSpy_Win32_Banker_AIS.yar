
rule TrojanSpy_Win32_Banker_AIS{
	meta:
		description = "TrojanSpy:Win32/Banker.AIS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_03_0 = {74 1e 8d 45 ?? 50 b9 01 00 00 00 8b d3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85 } //5
		$a_00_1 = {73 65 6e 68 61 } //1 senha
		$a_00_2 = {73 61 2a 6e 74 2a 61 6e 40 64 65 72 2e 40 63 23 6f 40 6d 2a } //1 sa*nt*an@der.@c#o@m*
		$a_00_3 = {73 40 61 2a 6e 2a 74 23 61 6e 40 64 2a 65 40 72 23 6e 23 65 74 2a } //1 s@a*n*t#an@d*e@r#n#et*
		$a_00_4 = {2a 46 40 69 40 72 2a 65 23 66 } //1 *F@i@r*e#f
		$a_00_5 = {40 43 2a 61 23 69 2a 78 40 61 } //1 @C*a#i*x@a
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}