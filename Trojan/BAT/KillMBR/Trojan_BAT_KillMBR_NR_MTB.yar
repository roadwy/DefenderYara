
rule Trojan_BAT_KillMBR_NR_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 4f 4e 41 00 46 69 6c 65 41 63 63 65 73 73 00 46 69 6c 65 53 68 61 72 65 00 46 41 43 4f 43 4c 42 4c 4e 49 45 49 46 4b 50 42 43 4a 48 43 43 48 45 46 49 41 50 44 4c 42 43 48 45 47 41 41 00 73 65 74 } //3 位䅎䘀汩䅥捣獥s楆敬桓牡e䅆佃䱃䱂䥎䥅䭆䉐䩃䍈䡃䙅䅉䑐䉌䡃䝅䅁猀瑥
		$a_01_1 = {76 47 48 39 73 37 43 37 6b 53 6b 70 4b 68 65 33 6a 57 } //1 vGH9s7C7kSkpKhe3jW
		$a_01_2 = {4e 4e 44 50 46 4a 4f 4e 42 42 4d 41 48 43 43 4d 41 43 47 43 49 46 46 4e 43 4e 4a 42 4d 44 4e 48 4d 43 4a 4e } //1 NNDPFJONBBMAHCCMACGCIFFNCNJBMDNHMCJN
		$a_01_3 = {64 32 64 35 32 30 65 31 2d 39 62 64 61 2d 34 61 38 37 2d 62 66 35 61 2d 35 65 38 31 37 35 61 32 65 62 34 64 } //1 d2d520e1-9bda-4a87-bf5a-5e8175a2eb4d
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}