
rule Trojan_BAT_ZillaCrypt_NG_MTB{
	meta:
		description = "Trojan:BAT/ZillaCrypt.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 11 07 59 17 5b 6a 69 0c 2b 19 07 03 17 } //2 ᅘ备嬗楪⬌ܙᜃ
		$a_01_1 = {00 08 16 32 14 09 16 32 10 09 08 31 0c 08 11 04 8e 69 fe 04 16 fe 01 2b 01 } //1
		$a_81_2 = {39 34 42 33 35 38 31 37 2d 45 39 43 41 2d 34 37 37 41 2d 39 46 34 32 2d 31 41 32 31 38 34 44 34 37 46 30 30 } //1 94B35817-E9CA-477A-9F42-1A2184D47F00
		$a_81_3 = {54 65 5a 46 66 6a 44 33 34 41 37 6a 76 47 37 35 6f 36 4e 71 39 43 39 } //1 TeZFfjD34A7jvG75o6Nq9C9
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}