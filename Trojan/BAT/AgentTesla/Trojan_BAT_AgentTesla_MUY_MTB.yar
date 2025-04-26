
rule Trojan_BAT_AgentTesla_MUY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {06 07 9a 0c ?? 08 6f ?? ?? ?? ?? 16 fe 02 ?? ?? 2c ?? ?? 7e ?? ?? ?? ?? 08 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? ?? ?? ?? 07 17 58 0b 07 06 8e 69 32 } //10
		$a_80_1 = {49 6e 76 6f 6b 65 } //Invoke  2
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  2
		$a_80_3 = {64 6f 77 71 6b 64 6f 6b 6f } //dowqkdoko  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}