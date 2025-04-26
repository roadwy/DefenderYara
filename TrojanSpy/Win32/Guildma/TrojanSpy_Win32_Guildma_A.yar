
rule TrojanSpy_Win32_Guildma_A{
	meta:
		description = "TrojanSpy:Win32/Guildma.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {61 72 71 75 65 69 72 6f [0-02] 2e 64 6c 6c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}