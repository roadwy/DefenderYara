
rule Trojan_Win32_NSISInject_RPF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 79 64 65 70 6c 61 64 73 31 36 36 } //1 Gydeplads166
		$a_01_1 = {52 61 67 73 6f 6b 6b 65 72 5c 46 72 69 6d 6f 64 69 67 68 65 64 2e 52 65 70 } //1 Ragsokker\Frimodighed.Rep
		$a_01_2 = {53 74 6f 72 6c 69 6e 6a 65 64 65 73 5c 43 6f 75 6e 74 65 72 74 75 67 2e 6c 6e 6b } //1 Storlinjedes\Countertug.lnk
		$a_01_3 = {53 6c 65 65 70 6d 61 72 6b 65 6e 5c 42 65 73 6d 69 74 74 65 6e 64 65 73 2e 69 6e 69 } //1 Sleepmarken\Besmittendes.ini
		$a_01_4 = {4b 75 70 6f 6e 6b 6c 69 70 70 65 72 65 6e } //1 Kuponklipperen
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RPF_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 61 00 66 00 68 00 6e 00 67 00 69 00 67 00 68 00 65 00 64 00 2e 00 53 00 6b 00 65 00 } //1 Attributafhngighed.Ske
		$a_01_1 = {52 00 65 00 70 00 6c 00 69 00 63 00 65 00 72 00 65 00 72 00 2e 00 53 00 75 00 6b 00 } //1 Replicerer.Suk
		$a_01_2 = {42 00 6f 00 6c 00 69 00 67 00 6d 00 69 00 6e 00 69 00 73 00 74 00 65 00 72 00 69 00 65 00 72 00 5c 00 50 00 6f 00 6c 00 69 00 6e 00 65 00 5c 00 42 00 69 00 73 00 61 00 67 00 2e 00 69 00 6e 00 69 00 } //1 Boligministerier\Poline\Bisag.ini
		$a_01_3 = {4c 00 61 00 63 00 74 00 61 00 73 00 65 00 2e 00 4b 00 6f 00 62 00 } //1 Lactase.Kob
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}