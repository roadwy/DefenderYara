
rule Trojan_Win32_ParadoxRat_RB_MTB{
	meta:
		description = "Trojan:Win32/ParadoxRat.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 31 44 56 61 38 78 6e 48 33 6f 44 6b 34 52 43 4f 71 74 75 61 7a 5a 57 44 44 51 48 64 44 55 34 46 32 4c 54 74 63 65 48 68 4b 32 6c 5a 65 4d 31 6e 4c 5a 4c 6e 6f 37 30 78 52 37 57 52 78 78 4d 6a 59 63 67 58 44 35 38 59 44 59 49 52 45 30 6a 4e 77 63 66 35 4b 41 6e 62 44 59 45 44 55 66 4d } //1 w1DVa8xnH3oDk4RCOqtuazZWDDQHdDU4F2LTtceHhK2lZeM1nLZLno70xR7WRxxMjYcgXD58YDYIRE0jNwcf5KAnbDYEDUfM
		$a_01_1 = {36 61 31 36 48 45 49 34 72 6d 4e 45 59 4c 6b 56 57 50 57 50 33 56 5a 55 34 6f 68 35 6a } //1 6a16HEI4rmNEYLkVWPWP3VZU4oh5j
		$a_01_2 = {52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 52 00 65 00 6d 00 6f 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 RootkitRemover.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}