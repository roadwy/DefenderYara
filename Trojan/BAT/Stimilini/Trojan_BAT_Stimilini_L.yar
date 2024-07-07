
rule Trojan_BAT_Stimilini_L{
	meta:
		description = "Trojan:BAT/Stimilini.L,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_00_0 = {49 6e 76 65 6e 74 6f 72 79 49 74 65 6d } //1 InventoryItem
		$a_00_1 = {53 65 6e 64 54 6f 54 72 61 64 65 } //1 SendToTrade
		$a_00_2 = {53 4c 6f 67 69 6e } //1 SLogin
		$a_00_3 = {53 74 65 61 6d 53 65 73 73 69 6f 6e } //1 SteamSession
		$a_80_4 = {72 65 63 61 70 74 63 68 61 } //recaptcha  2
		$a_00_5 = {50 6f 6b 65 53 53 2e 64 6c 6c } //5 PokeSS.dll
		$a_80_6 = {3a 2f 2f 70 6f 6b 65 73 74 65 61 6c 65 72 2e 63 6f 6d } //://pokestealer.com  10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*2+(#a_00_5  & 1)*5+(#a_80_6  & 1)*10) >=16
 
}