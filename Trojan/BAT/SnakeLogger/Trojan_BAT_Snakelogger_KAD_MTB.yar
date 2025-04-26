
rule Trojan_BAT_Snakelogger_KAD_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_80_0 = {42 6c 61 63 6b 48 61 77 6b 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //BlackHawk\User Data\Default\Login Data  5
		$a_80_1 = {53 6e 61 6b 65 4b 65 79 6c 6f 67 67 65 72 } //SnakeKeylogger  1
		$a_80_2 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //software\microsoft\windows\currentversion\run  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}