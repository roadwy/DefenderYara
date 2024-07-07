
rule TrojanDownloader_Win32_Lerspeng_A{
	meta:
		description = "TrojanDownloader:Win32/Lerspeng.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 1e 00 00 "
		
	strings :
		$a_01_0 = {69 c0 01 01 01 01 57 8b 7d 08 c1 e9 02 f3 ab 8b ce 83 e1 03 f3 aa 5f } //8
		$a_01_1 = {4d 42 41 50 4f 32 33 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c } //-8 䉍偁㉏㈳搮汬䐀汬慃啮汮慯乤睯䐀汬
		$a_03_2 = {83 f8 01 75 5b 39 7d fc 74 06 83 7d fc 06 75 50 8d 85 90 01 02 ff ff 50 ff 15 90 00 } //4
		$a_00_3 = {83 f8 01 74 0f 83 c6 04 81 fe d4 00 00 00 0f 82 } //3
		$a_01_4 = {65 73 6f 66 74 6d 65 63 68 61 6e 69 63 73 2e 63 6f 6d 2f 73 70 65 6e 67 6c 65 72 2f 62 65 61 74 6c 65 } //2 esoftmechanics.com/spengler/beatle
		$a_01_5 = {66 6c 6f 6f 72 6d 61 73 74 65 72 73 61 6e 64 69 65 67 6f 2e 63 6f 6d 2f 69 6d 70 75 67 6e 69 6e 67 2f 66 65 6c 73 69 74 69 63 } //1 floormastersandiego.com/impugning/felsitic
		$a_01_6 = {32 31 37 2e 31 39 39 2e 31 36 31 2e 37 38 2f 6d 69 73 68 61 70 70 69 6e 67 2f 66 6c 65 65 63 65 61 62 6c 65 } //1 217.199.161.78/mishapping/fleeceable
		$a_01_7 = {77 77 77 2e 6e 70 62 63 67 61 73 2e 6e 65 74 2f 64 79 73 6c 65 78 69 61 2f 68 6f 72 69 7a 6f 6e 6c 65 73 73 } //1 www.npbcgas.net/dyslexia/horizonless
		$a_01_8 = {61 6c 70 68 61 33 36 30 2e 63 6f 2e 75 6b 2f 6d 65 72 76 69 6e 2f 6e 75 6d 62 65 72 } //1 alpha360.co.uk/mervin/number
		$a_01_9 = {70 61 73 73 70 6f 72 74 74 6f 70 6c 61 79 2e 63 6f 2e 75 6b 2f 64 75 66 66 65 72 2f 73 61 6c 75 74 61 74 69 6f 6e 73 } //1 passporttoplay.co.uk/duffer/salutations
		$a_01_10 = {32 30 32 2e 31 36 34 2e 34 31 2e 32 35 31 2f 67 6f 69 74 65 72 73 2f 77 6f 6e 64 65 72 6c 65 73 73 } //1 202.164.41.251/goiters/wonderless
		$a_01_11 = {63 61 6c 75 6d 65 74 63 6f 6c 6c 65 63 74 69 6f 6e 2e 63 6f 6d 2f 61 64 76 65 72 62 2f 73 6f 6e 67 6c 65 73 73 } //1 calumetcollection.com/adverb/songless
		$a_01_12 = {2e 6c 75 78 75 72 79 62 6f 75 74 69 71 75 65 68 6f 74 65 6c 73 61 6e 64 76 69 6c 6c 61 73 2e 63 6f 6d 2f 71 75 61 6c 6d 2f 6f 6e 64 65 72 } //1 .luxuryboutiquehotelsandvillas.com/qualm/onder
		$a_01_13 = {77 6f 6f 64 65 6e 2d 66 6c 6f 6f 72 69 6e 67 2e 6f 72 67 2e 75 6b 2f 73 74 65 72 6e 2f 6a 75 73 74 } //1 wooden-flooring.org.uk/stern/just
		$a_01_14 = {65 76 69 6c 2e 68 6e 2e 76 63 2f 65 6c 61 73 74 69 63 2f 70 6c 65 61 73 65 } //1 evil.hn.vc/elastic/please
		$a_01_15 = {63 61 70 69 74 61 6c 2d 61 75 74 6f 2d 73 63 72 61 70 2e 63 6f 2e 75 6b 2f 73 63 75 7a 7a 69 65 72 2f 64 6f 6f 6d } //1 capital-auto-scrap.co.uk/scuzzier/doom
		$a_01_16 = {74 72 65 73 65 73 65 6e 74 61 2e 63 6f 2f 6d 6f 72 65 73 2f 77 61 69 74 } //1 tresesenta.co/mores/wait
		$a_01_17 = {6d 62 61 73 69 73 74 65 6d 61 73 2e 63 6f 6d 2e 61 72 2f 65 6e 6e 6f 62 6c 65 73 2f 6d 6f 6d 65 6e 74 } //1 mbasistemas.com.ar/ennobles/moment
		$a_01_18 = {73 61 65 73 70 6f 2e 63 6f 6d 2f 63 61 72 70 65 64 2f 6c 6f 6f 73 65 } //1 saespo.com/carped/loose
		$a_01_19 = {62 63 6c 63 61 72 61 6e 64 63 6f 6d 6d 65 72 63 69 61 6c 73 2e 63 6f 2e 75 6b 2f 74 72 61 6e 73 65 70 74 73 2f 79 6f 75 72 } //1 bclcarandcommercials.co.uk/transepts/your
		$a_01_20 = {73 6b 69 6c 69 66 74 68 6f 66 65 63 6b 2e 64 65 2f 67 65 72 61 72 64 6f 2f 62 69 67 67 65 73 74 } //1 skilifthofeck.de/gerardo/biggest
		$a_01_21 = {6d 65 64 6f 73 61 2e 63 6f 6d 2e 74 72 2f 70 65 6e 6e 6f 6e 73 2f 66 61 6e } //1 medosa.com.tr/pennons/fan
		$a_01_22 = {66 74 70 2e 63 62 72 69 64 67 65 73 2e 6f 72 67 2f 63 61 6a 6f 6c 69 6e 67 2f 6d 61 6b 65 } //1 ftp.cbridges.org/cajoling/make
		$a_01_23 = {62 69 67 35 6f 70 73 2e 63 6f 2e 7a 61 2f 77 69 6c 6c 69 6e 67 2f 68 69 6c 6c } //1 big5ops.co.za/willing/hill
		$a_01_24 = {61 72 69 6b 2d 61 69 72 6c 69 6e 65 75 6b 2e 63 6f 2e 75 6b 2f 68 61 62 69 74 2f 64 61 79 } //1 arik-airlineuk.co.uk/habit/day
		$a_01_25 = {70 61 72 72 6f 71 75 69 61 6c 61 64 69 76 69 6e 61 6d 69 73 65 72 69 63 6f 72 64 69 61 2e 63 6f 6d 2f 73 74 61 72 6c 65 73 73 2f 66 72 65 65 } //1 parroquialadivinamisericordia.com/starless/free
		$a_01_26 = {77 69 6e 74 68 65 72 73 61 63 68 65 6e 2e 64 65 2f 77 72 69 67 67 6c 79 2f 6d 6f 6d 65 6e 74 } //1 winthersachen.de/wriggly/moment
		$a_01_27 = {66 74 70 2e 76 69 70 62 61 6c 61 64 61 2e 63 6f 6d 2f 6f 6c 64 75 76 61 69 2f 6a 75 73 74 } //1 ftp.vipbalada.com/olduvai/just
		$a_01_28 = {66 66 67 63 6f 72 70 6f 72 61 74 65 2e 63 6f 6d 2f 63 6c 75 6e 67 2f 7a 65 72 6f } //1 ffgcorporate.com/clung/zero
		$a_01_29 = {2e 6c 6c 61 6e 74 61 73 63 61 73 61 67 72 61 6e 64 65 2e 63 6f 6d 2f 63 75 73 73 65 64 2f 6b 69 6c 6c } //1 .llantascasagrande.com/cussed/kill
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*-8+(#a_03_2  & 1)*4+(#a_00_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1) >=13
 
}