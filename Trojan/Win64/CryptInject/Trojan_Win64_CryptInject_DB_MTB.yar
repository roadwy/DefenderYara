
rule Trojan_Win64_CryptInject_DB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {37 00 31 00 2e 00 44 00 4c 00 4c 00 } //1 71.DLL
		$a_01_1 = {66 75 63 6b 6f 66 66 2e 65 78 65 } //1 fuckoff.exe
		$a_01_2 = {5c 72 65 70 6f 73 5c 46 75 63 6b 4f 46 46 52 75 6e 50 45 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 46 75 63 6b 4f 46 46 52 75 6e 50 45 2e 70 64 62 } //1 \repos\FuckOFFRunPE\x64\Release\FuckOFFRunPE.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}