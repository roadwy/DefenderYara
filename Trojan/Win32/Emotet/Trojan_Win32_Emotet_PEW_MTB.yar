
rule Trojan_Win32_Emotet_PEW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e2 ff 00 00 00 03 c2 99 f7 fb 8a 1c 2e 8a 44 14 ?? 32 c3 88 06 90 09 04 00 8a 44 3c } //1
		$a_81_1 = {6a 39 43 46 56 65 78 33 33 33 64 41 79 2a 32 3f 42 71 78 78 38 58 41 4f 6a 54 6f 6f 6e 55 76 43 6a 38 6e 7b 51 55 64 74 31 4b 6a 43 43 6a 65 4b 41 4f 25 70 48 4a 63 70 34 7d 30 6b 6f 37 78 52 72 44 58 71 25 55 6d 74 45 57 43 43 30 61 65 79 66 65 40 } //1 j9CFVex333dAy*2?Bqxx8XAOjToonUvCj8n{QUdt1KjCCjeKAO%pHJcp4}0ko7xRrDXq%UmtEWCC0aeyfe@
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}