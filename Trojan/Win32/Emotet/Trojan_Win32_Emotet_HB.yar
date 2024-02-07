
rule Trojan_Win32_Emotet_HB{
	meta:
		description = "Trojan:Win32/Emotet.HB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 58 78 71 61 33 4d 6b 54 30 4a 48 63 32 74 4d 59 57 6c 30 57 57 64 49 57 6c 70 30 66 56 46 72 61 54 39 34 52 6e 56 51 59 6a 6c 57 4d 51 } //01 00  OXxqa3MkT0JHc2tMYWl0WWdIWlp0fVFraT94RnVQYjlWMQ
		$a_01_1 = {78 74 48 67 77 4b 45 7c 4b 4e 25 49 4c 4d 3f 5a 30 63 47 40 7a 2a 23 62 38 34 52 32 33 54 36 48 46 38 } //00 00  xtHgwKE|KN%ILM?Z0cG@z*#b84R23T6HF8
	condition:
		any of ($a_*)
 
}