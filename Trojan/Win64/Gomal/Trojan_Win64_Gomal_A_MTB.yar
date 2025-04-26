
rule Trojan_Win64_Gomal_A_MTB{
	meta:
		description = "Trojan:Win64/Gomal.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 3b 66 10 0f 86 ?? 00 00 00 55 48 89 e5 48 83 ec 40 48 89 44 24 50 48 89 c3 48 89 d9 48 8d 05 7c 0e 01 00 e8 97 39 f6 ff 48 89 44 24 28 48 8b 5c 24 50 48 89 d9 e8 c5 0e fc ff ?? ?? ?? ?? ?? 48 85 db 74 36 } //2
		$a_03_1 = {49 3b 66 10 0f 86 c2 00 00 00 55 48 89 e5 48 83 ec 50 66 44 0f d6 7c 24 48 48 89 5c 24 68 48 89 44 24 60 c6 44 24 37 00 b9 31 00 00 00 bf 06 00 02 00 b8 01 00 00 80 48 8d 1d 0b b6 04 00 66 ?? e8 5b d6 ff ff 48 85 db 75 70 } //2
		$a_01_2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 44 68 50 52 74 4b 6e 33 68 44 47 73 33 6c 69 44 41 48 43 74 2f 6d 56 57 71 62 47 39 7a 38 67 63 66 62 52 47 75 72 70 39 33 2f 6a 48 38 7a 78 49 63 33 41 57 5f 79 59 4d 75 48 4b 65 52 33 2f 73 51 63 69 66 63 4a 54 6e 72 35 74 72 66 61 65 37 30 43 70 } //1 Go build ID: "DhPRtKn3hDGs3liDAHCt/mVWqbG9z8gcfbRGurp93/jH8zxIc3AW_yYMuHKeR3/sQcifcJTnr5trfae70Cp
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}