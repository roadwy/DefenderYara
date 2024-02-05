
rule Trojan_BAT_Disstl_AF_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {5b 5c 77 2d 5d 7b 32 34 7d 5c 2e 5b 5c 77 2d 5d 7b 36 7d 5c 2e 5b 5c 77 2d 5d 7b 32 37 7d } //[\w-]{24}\.[\w-]{6}\.[\w-]{27}  03 00 
		$a_80_1 = {6d 66 61 5c 2e 5b 5c 77 2d 5d 7b 38 34 7d } //mfa\.[\w-]{84}  03 00 
		$a_80_2 = {64 69 73 63 6f 72 64 63 61 6e 61 72 79 } //discordcanary  03 00 
		$a_80_3 = {44 69 73 63 6f 72 64 20 54 6f 6b 65 6e 20 47 72 61 62 62 65 72 } //Discord Token Grabber  03 00 
		$a_80_4 = {47 72 61 62 62 65 72 42 75 69 6c 64 65 72 43 4f 44 45 } //GrabberBuilderCODE  03 00 
		$a_80_5 = {57 65 62 68 6f 6f 6b } //Webhook  03 00 
		$a_80_6 = {53 65 6e 64 54 6f 6b 65 6e } //SendToken  00 00 
	condition:
		any of ($a_*)
 
}