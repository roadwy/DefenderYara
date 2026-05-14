
rule Trojan_BAT_Lasy_PGLA_MTB{
	meta:
		description = "Trojan:BAT/Lasy.PGLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_80_0 = {70 61 39 33 75 31 48 38 61 77 34 55 61 4f 52 31 38 53 37 73 52 59 62 6d 37 38 42 49 65 6c 6d 49 67 50 74 36 62 51 30 61 50 6b 61 57 6c 58 66 71 48 64 35 78 4c 53 74 69 6e 58 48 4e 47 38 77 2b 73 75 76 2b 38 57 6c 4e 5a 76 75 5a 34 6d 41 53 4e 7a 67 67 56 4b 79 4d 56 4a 6f 46 38 6d 55 44 49 6d 50 35 55 4d 73 33 6c 6a 61 } //pa93u1H8aw4UaOR18S7sRYbm78BIelmIgPt6bQ0aPkaWlXfqHd5xLStinXHNG8w+suv+8WlNZvuZ4mASNzggVKyMVJoF8mUDImP5UMs3lja  5
	condition:
		((#a_80_0  & 1)*5) >=5
 
}