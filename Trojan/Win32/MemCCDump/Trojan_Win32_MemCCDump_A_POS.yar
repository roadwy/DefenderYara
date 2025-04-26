
rule Trojan_Win32_MemCCDump_A_POS{
	meta:
		description = "Trojan:Win32/MemCCDump.A!POS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 6f 75 6e 64 20 74 72 61 63 6b 20 64 61 74 61 20 61 74 20 25 73 20 77 69 74 68 20 50 49 44 20 25 64 21 } //1 Found track data at %s with PID %d!
		$a_01_1 = {44 75 6d 70 31 6e 67 20 70 31 69 76 34 74 33 20 6d 33 6d 72 79 } //1 Dump1ng p1iv4t3 m3mry
		$a_01_2 = {28 28 42 28 28 5b 30 2d 39 5d 7b 31 33 2c 31 36 7d 29 7c 28 5b 30 2d 39 5d 7c 5c 73 29 7b 31 33 2c 32 35 7d 29 5c 5e 5b 41 2d 5a 5c 73 30 2d 39 5d 7b 30 2c 33 30 7d 5c 2f 5b 41 2d 5a 5c 73 30 2d 39 5d } //1 ((B(([0-9]{13,16})|([0-9]|\s){13,25})\^[A-Z\s0-9]{0,30}\/[A-Z\s0-9]
		$a_01_3 = {7c 28 3c 46 69 65 6c 64 20 6e 61 6d 65 3d 22 43 61 72 64 4e 75 6d 62 65 72 22 3e 5b 30 2d 39 5d 7b 31 35 2c 31 39 7d 3c 2f 46 69 65 6c 64 3e 29 29 } //1 |(<Field name="CardNumber">[0-9]{15,19}</Field>))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_MemCCDump_A_POS_2{
	meta:
		description = "Trojan:Win32/MemCCDump.A!POS,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 61 72 64 4e 75 6d 62 65 72 22 3e 5b 30 2d 39 5d 7b 31 35 2c 31 39 7d 3c 2f 46 69 65 6c 64 3e 29 7c 28 7e 43 43 4d 5b 30 2d 39 5d 7b 31 35 2c 31 39 7d 44 5b 30 2d 39 5d 7b 34 7d 7e 29 29 00 } //1 慃摲畎扭牥㸢せ㤭筝㔱ㄬ紹⼼楆汥㹤簩縨䍃孍ⴰ崹ㅻⰵ㤱䑽せ㤭筝紴⥾)
		$a_01_1 = {46 6f 75 6e 64 20 74 72 61 63 6b 20 64 61 74 61 20 61 74 20 25 73 20 77 69 74 68 20 50 49 44 20 } //1 Found track data at %s with PID 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_MemCCDump_A_POS_3{
	meta:
		description = "Trojan:Win32/MemCCDump.A!POS,SIGNATURE_TYPE_PEHSTR,7d 00 7d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {44 69 61 62 6c 6f 48 6f 72 6e 20 28 50 72 6f 75 64 20 4d 65 6d 62 65 72 20 6f 66 3a 20 4b 44 2d 54 65 61 6d 29 } //50 DiabloHorn (Proud Member of: KD-Team)
		$a_01_1 = {44 75 6d 70 69 6e 67 20 70 72 69 76 61 74 65 20 6d 65 6d 6f 72 79 20 66 6f 72 20 70 69 64 20 25 73 20 74 6f 20 25 73 2e 64 6d 70 2e 2e 2e } //50 Dumping private memory for pid %s to %s.dmp...
		$a_01_2 = {50 72 6f 63 65 73 73 20 4d 65 6d 6f 72 79 20 44 75 6d 70 65 72 } //10 Process Memory Dumper
		$a_01_3 = {46 6f 75 6e 64 20 74 72 61 63 6b 20 64 61 74 61 20 61 74 20 25 73 20 77 69 74 68 20 50 49 44 20 25 64 21 } //10 Found track data at %s with PID %d!
		$a_01_4 = {73 73 6c 67 77 2e 65 78 65 00 } //5
		$a_01_5 = {76 69 73 61 64 2e 65 78 65 00 } //5
		$a_01_6 = {61 64 69 68 74 74 70 73 65 72 76 65 72 73 76 63 2e 65 78 65 00 } //5
		$a_01_7 = {69 62 65 72 71 73 2e 65 78 65 00 } //5
		$a_01_8 = {65 64 63 73 76 72 2e 65 78 65 00 } //5
		$a_01_9 = {63 61 6c 73 72 76 2e 65 78 65 00 } //5
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*50+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=125
 
}